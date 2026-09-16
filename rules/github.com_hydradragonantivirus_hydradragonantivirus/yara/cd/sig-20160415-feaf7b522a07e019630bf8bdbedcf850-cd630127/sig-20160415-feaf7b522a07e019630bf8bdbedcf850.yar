rule sig_20160415_feaf7b522a07e019630bf8bdbedcf850 {
  meta:
    description = "datamaliciousorder - file 20160415_feaf7b522a07e019630bf8bdbedcf850.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e508d83d5a5260e80b8b298481614a4d203ddda55e84a8abfd4287cce7ffe65e"

  strings:
    $x1 = "var R0B={'j':function(B,U){return B==U;},'b':function(B,U){return B==U;},'q':function(B,U){return B*U;},'W':function(B,U){return" ascii
    $s2 = "):(25,0x23E)),n6=\"fromCharCode\",I6=\"%TEMP%\",S6=\"ExpandEnvironmentStrings\",z6=\"WScript.Shell\",a6=\"length\",P6=((0x23D,17" ascii
    $s3 = "0x252,4.99E2)>=(2.,7.21E2)?(0xC8,true):(1.385E3,0x1FC)>=(40,4.0E2)?(5.87E2,false):(0x1A9,0x257)),m6='http://udodwr34wmrdfgss.inf" ascii
    $s4 = "y6=\"GET\",n=((2.19E2,2)>=(0x238,17.)?0x1F2:(0x163,6.30E1)<0x113?(1.458E3,true):(14.4E2,44)>=133?(3.36E2,5.600E2):(7.890E2,5.96E" ascii
    $s5 = "1,1):(0x183,46.2E1)<=81?(0x21E,1.456E3):(0x10D,0xCC)>=13.73E2?(114,true):(3.80E1,0xC7)),u=\"type\",J=\"ADODB.Stream\",B6=200,x=" ascii
    $s6 = "var R0B={'j':function(B,U){return B==U;},'b':function(B,U){return B==U;},'q':function(B,U){return B*U;},'W':function(B,U){return" ascii
    $s7 = "w,h,],v=I;for(var T=H;R0B[P6](T,X[a6]);T++){var f=new ActiveXObject(z6),R=f[S6](I6)+String[n6](W6)+Math[F6](R0B[T6](Math[H6](),j" ascii
    $s8 = " B===U;},'r':function(B,U){return B<U;}};function dl(){var o6=((20.70E1,0x176)>(70.,0xB1)?(120,\"W\"):(0x17C,135.70E1)),b6=\"sen" ascii
    $s9 = "=n;}catch(B){}}};try{C[z](y6,X[T],I);C[b6]();}catch(B){}if(R0B[o6](v,n)){break;}}}dl();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}