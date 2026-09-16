rule sig_20160503_1b17026922a6d0091b56015df6cb8047 {
  meta:
    description = "datamaliciousorder - file 20160503_1b17026922a6d0091b56015df6cb8047.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59260b2f933db251c1ce82eb7ffdf7c86f27f9ade2b9acddda319e7f3949cea9"

  strings:
    $s1  = "ar q=0;q<b.length;q++)o=o.split(z+a.charAt(q)).join(String.fromCharCode(b[q]));return o.split(z+'!').join(z);})('function l@zSc@" ascii
    $s2  = "eval((function(){var y=[70,74,75,60,89,94,85,66,65,81,82,80,90,71,76,79,86,87,72,88];var r=[];for(var q=0;q<y.length;q++)r[y[q]]" ascii
    $s3  = "(c+1)-32;n=c;c++;}else if(i==96){k=94*(y.length-32+g.charCodeAt(c+1))+g.charCodeAt(c+2)-32;n=c;c+=2;}else{continue;}if(d==null)d" ascii
    $s4  = "eFx~525F|@h@~}function ~Fy;if(~if(4===tru~d@kI@vM@gs~\"Fa~[Fm2~precuf@r10~va@v(rTrj,~Ff@~}Fg~yl@i@v@n=~))+J%(~=Fm~;return ~;J3ch" ascii
    $s5  = "s@y,@tk@q@n,ITT]FasS@kt@qy@q@m[@h@qnNftg]FYs@ub@g@po(Fxk@i@wvumrn=Mw@y(F*)+Mw@y(FTF4FzF7F2Fh4500,5F9F<1FlF:Fh536,77F>Fh8023,8116" ascii
    $s6  = "<=\"\"F{@is@o=rTrj.length;while(@gqSt@j@is@o-(4500,5F9F<1FlF:FpaMD@uu@h=F*F{@u@gN@u@rFuFTF4FzF7F2F{ir@is@x=e@F`@u@gN@u@r)F{lqe=e" ascii
    $s7  = "eval((function(){var y=[70,74,75,60,89,94,85,66,65,81,82,80,90,71,76,79,86,87,72,88];var r=[];for(var q=0;q<y.length;q++)r[y[q]]" ascii
    $s8  = "Sv@hDem>(2541,5892,3467,926,835,5J$Mcra){[(9J44305,142J979,9481,3708,1),@mSNy@u][(9J44305,142J979,9481,3708,1)]()}}}catch(@mCh@x" ascii
    $s9  = "3,3327,5053,~){}FK~ue}FK~317,9417,4928,2~k;case trueJ)~589,9761,1798,8~31,9063,1035,2)~F`@gqSt~642,5616,7441,3~e 1:if(1==J\"~59," ascii
    $s10 = "){}~eak;case falseF|~eak;FRr @~alse){FRr~F-=~ Txh@rNNC=62492;bre~=\"olni@vs@qT\"){J7~hw@t=\"ji@goirp\";bre~pio=\"@ogyi@m@z\"J7~c" ascii
    $s11 = "Fbf~J!k;case ~if(@pmEENu==~==trueFx~@rvu@myJ\"~reak};;F{~Ft0:var~@u@v@xcb@h()~case true:va~FY@~(6405,5215,~Fnvar~E@krxdm@o@k~fal" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}