rule sig_20160503_392060d2832c2b9ffda79f51fe1e886b {
  meta:
    description = "datamaliciousorder - file 20160503_392060d2832c2b9ffda79f51fe1e886b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b223133b3f65ecf785f6e374cc9250b7e6e8f7b7b10cbc9492bac8b222df07f5"

  strings:
    $s1  = "eval((function(){var o=[66,60,81,79,80,86,90,75,85,82,94,65,71,70,76,87,74,72,89,88];var d=[];for(var a=0;a<o.length;a++)d[o[a]]" ascii
    $s2  = "ar a=0;a<f.length;a++)z=z.split(p+n.charAt(a)).join(String.fromCharCode(f[a]));return z.split(p+'!').join(p);})('function C@jk@s" ascii
    $s3  = "@y@vj\"){}BLip@y@jB@pia(wCr,l@o@p@ybN@s@rBZa@vbC=wCr[w@yC()](l@o@p@ybN@s@rBM3BW\"@w@ir@i@unzkB`ce@oeEe@mB]B90:if(1===\"@tC@yNg@s" ascii
    $s4  = ",5143,7400,3843,3471,8320,5BkhM@pet){[(6958,7204,1692,216,1),u@v@y][(6958,7204,1692,216,1)]()}}else {if(tEenm@o(true)BNx@g@z@ut(" ascii
    $s5  = "eval((function(){var o=[66,60,81,79,80,86,90,75,85,82,94,65,71,70,76,87,74,72,89,88];var d=[];for(var a=0;a<o.length;a++)d[o[a]]" ascii
    $s6  = " ~))BH~BUvar ~==trueBZ~=(6981,2778,~BW1:var~=hqh@u@k@xE(~BB@~ryjxlxBj~}function ~=p@t@gp(\"0~[p@t@gp(\"0~j@u@tDqEhl~B];if(~x@nDi" ascii
    $s7  = "r@w@neoa.length;while(qyh@h@sb@wrTyc-(35B+BZbtdjEB=B!BsB\"BhI@mfx@sg=Bd77B*B[z@tIo@iIB#I@mfx@sgB\\\\skg@ymB#qyh+(35B+B\\\\pgos@t" ascii
    $s8  = "(e+1)-32;v=e;e++;}else if(q==96){l=94*(o.length-32+j.charCodeAt(e+1))+j.charCodeAt(e+2)-32;v=e;e+=2;}else{continue;}if(t==null)t" ascii
    $s9  = "1,1,\"fhku@j\")}}}catch(yec@ji){}~reak;case trueBi~4293,8885,1780,6236~6,1176,1884,4553,0)~=T@ju@x@g(r@w@neoa,~B,;~;if(EddBN};b~" ascii
    $s10 = "u()~+@m@lwrI((~@le@jt@s10~kqCDez@m@u~\"BR~BR@~);sBa~=B]){~Bj;if(~p@t@rbe()~==0BZ~;return ~=1BZ~(BZ@~;break};~(B\\\\~){case ~l@mh" ascii
    $s11 = "B2q~ SajsbT@l=\"CCpyy\";~m@ix@s@oBD~k;case falseBi~{B5\"~eak;case 0Biu~))B8~switch(1BW~w@lk@g=58021;b~}B9~+rME@p@j@wk((~;break;c" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}