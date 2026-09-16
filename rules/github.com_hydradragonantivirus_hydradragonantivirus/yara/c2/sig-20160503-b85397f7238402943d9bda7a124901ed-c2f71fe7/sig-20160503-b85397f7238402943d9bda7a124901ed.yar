rule sig_20160503_b85397f7238402943d9bda7a124901ed {
  meta:
    description = "datamaliciousorder - file 20160503_b85397f7238402943d9bda7a124901ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e6524306c916fb5f6c5acbcf6b5deb4d61d35d688b1a420cb09360050f24590"

  strings:
    $s1  = "ar c=0;c<b.length;c++)a=a.split(x+r.charAt(c)).join(String.fromCharCode(b[c]));return a.split(x+'!').join(x);})('function d@mlT@" ascii
    $s2  = "eval((function(){var e=[70,87,71,94,74,81,86,80,72,89,76,60,85,90,65,82,88,66,75,79];var k=[];for(var c=0;c<e.length;c++)k[e[c]]" ascii
    $s3  = "Fp};~Fk;if(~=@hFu+~98,688,154~F\\\\9~trueFh~=@hw@tdhq(~){switch(~\"F^~)F^~=Fk){~uk@pedz()~@stDx@mM(~hFu);~4,5953,45~7041,2164~;r" ascii
    $s4  = "eval((function(){var e=[70,87,71,94,74,81,86,80,72,89,76,60,85,90,65,82,88,66,75,79];var k=[];for(var c=0;c<e.length;c++)k[e[c]]" ascii
    $s5  = "(z+1)-32;m=z;z++;}else if(v==96){y=94*(e.length-32+t.charCodeAt(z+1))+t.charCodeAt(z+2)-32;m=z;z+=2;}else{continue;}if(j==null)j" ascii
    $s6  = "s@vCMFlbreak}Fgg@v@pnen=10610}try{if(d@mlT@s@v(true)==0){if(@s@muI@pou(524,Ft==0){e@i@hz@h(664)}}Fgizllqk=([(756,5913,3005,5587," ascii
    $s7  = "ar ~9596,1614,725,~34,3153,2893,3~fuFB~12,8264,3448,1~21,1448,5303,2~ak;cW,false:~break}F_~F@@~@k@wySFk};~}FA~,4121,5663,64~FD@~" ascii
    $s8  = "@qs@y@m@l\"Fp}FgoThD@te@mFk;;F|Fc\"\"Fgt@u@v@ogt=@zdkbM.length;while(@hFu@r@t@u@v@ogt-(6114F>F8)FhgT@yoN=FmF&F$F!FghcxTFPFHF434F" ascii
    $s9  = "rn ~;switch(~Fe@~(Fhu~)Fo1~i@w@yuz=~Fh@~(Fj~691:var~F|@~){W)~W @~)F|~=false~F};~(334,5~lMy@ir~{cW,~;break~if(3==~\"W ~azkh@s~fal" ascii
    $s10 = ",3642,1)]()}}catch(@gi@hl){}~F$2~23,9547,828,9456,0)~@hSh@opk@i(@zdkbM,@~F&3~3,2438,179,4202,48~){F/@~598,6861,3764,891~F+\"~\"W" ascii
    $s11 = "@nivq\"Fhm~Fp;case ~[FG~FLr~rueW(2===\"~FM@~))+@hTr@l((~owsx@u@o(\"0~(9208,4554,~@z@h@h@nr@v~FQ,~,9416,235,3~F|sbyz=t~}function " ascii
    $s12 = "rx@id@y==1)~\"){F=~F.\"~ vrx@id@y=\"ecIcr~))+@z@nc@sx@v((~F2b~bT==\"yokE@ld@uf~case trueW ~673Fik@tbT~=54711Fp;c~=20702W!k@t~Fp}" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}