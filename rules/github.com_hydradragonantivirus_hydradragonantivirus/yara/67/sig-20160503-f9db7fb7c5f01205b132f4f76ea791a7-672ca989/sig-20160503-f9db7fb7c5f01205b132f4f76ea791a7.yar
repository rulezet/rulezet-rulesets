rule sig_20160503_f9db7fb7c5f01205b132f4f76ea791a7 {
  meta:
    description = "datamaliciousorder - file 20160503_f9db7fb7c5f01205b132f4f76ea791a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "596b6cba1521872210e911138265f2ea1f2aa1b1ea92bcabd322fe7879a8641d"

  strings:
    $s1  = "ar j=0;j<i.length;j++)t=t.split(e+u.charAt(j)).join(String.fromCharCode(i[j]));return t.split(e+'!').join(e);})('function @uyb@r" ascii
    $s2  = "eval((function(){var q=[72,79,66,65,70,81,88,82,94,71,86,75,76,89,87,85,90,60,80,74];var n=[];for(var j=0;j<q.length;j++)n[q[j]]" ascii
    $s3  = "(o+1)-32;h=o;o++;}else if(x==96){k=94*(q.length-32+r.charCodeAt(o+1))+r.charCodeAt(o+2)-32;h=o;o+=2;}else{continue;}if(v==null)v" ascii
    $s4  = "Ep@u=8185HxneEp@u=HBubDb@s=\"vi@yo\"H>266Hn@p@vuj=38387Hop@vuj===O/HV;HmHf=\"\"Hmu@mN@n@h=g@gDbt.length;while(Hp@xu@mN@n@h-(8129" ascii
    $s5  = "qHxpm@y==1Hilf@w@mE@n=\"@qbon@mbD\"};break}HT1HKybIEq@v(@nioo@nECHiz@vtI=parseInt(@nioo@nEC)HTz@vtIHKea@uE(Hid@sm@nNw=\"fHRd@sm@" ascii
    $s6  = "024022007O&46H{zn@hj@yp@uH512O.35016028H{)HU1H*7=Hq){H>537Hnn@v@tCx@nv=18139;break}HU6Ha\"o@zp@jHs @gvqiHjH$HwTItwg=\"@nq@v@j\"H" ascii
    $s7  = "T@yl@liudHKvq@mc(dIol@ggqHcta@gjC=[ea@uE(),HD,HI,\"m\",@HQ,\"h\",HZ),HD,@HQ,HI,\"d\",CkiEO\"()HOta@gjC[dIol@ggq]HKjI@r(Hixceue@k" ascii
    $s8  = "H$Hw@wx@maap@l=50618Howx@maap@l=H_ swzSglHj};bH sSdt@q@pn=\"ek@qe@j@s@g\";break}H/0Hn@ga@vT=\"@p@lgz@vzu\"Hoga@vT=H_ @mlIx@mHj}H" ascii
    $s9  = "eval((function(){var q=[72,79,66,65,70,81,88,82,94,71,86,75,76,89,87,85,90,60,80,74];var n=[];for(var j=0;j<q.length;j++)n[q[j]]" ascii
    $s10 = "HKHD{HwTas@rp@qN=\"rHRTas@rp@qNHFHQ{Hwexn@i=\"CHRexn@iHFuzlC(Hix@mD@t@lNx=\"@jHRx@mD@t@lNxHKHI{switch(trueHa34HnkazIbD=9443Hxkaz" ascii
    $s11 = "witch(@q@weHa1HngnIN@pd=76283H$if(@qC@wb===207){H>\"pin@k@wHs @zh@luoh@u=61802Hozh@luoh@u===57O/Hmn@gfDI@w=\"@v@papi@k\";bH v@k@" ascii
    $s12 = "6566,1~HK@~Hdvar ~=Hj){};~mlCCg@q@g()~dev@r@g@p((~}function ~[mkwS@i(\"0~=mkwS@i(\"0~))HY~]HT@~){switch(2~i@ib@hyd()~\"HT~2==0){" ascii
    $s13 = "HBr@w@nuf=62087H>\"by@lHs MkNup@mHjHC0Hn@vE@i=\"Dt@p@z\"HovE@i==416Hiw@iN=15333};HGa@p@kzx=59717;;Hmhgpk@n@ic=\"oHRhgpk@n@icHKSm" ascii
    $s14 = ",),@gTI][(8322,6549,2833,3783,6622,8601,3790,1719,9494,7836,93O%O,)]()}}}catch(@tE@tN){}~reak;case tH]~H%2~2,8911,1698,2610,0)~=" ascii
    $s15 = "36,7029,2195,1)~5423,3889,5727,9~HU7){case ~924,6168,3918,2)~H4y~y@i@kCqf=59460};~H;(~(6=HB~);fsrHL~))+HJ~uz==Hq){};b~,7521,8591" ascii
    $s16 = "~;return ~;switch(~;Hd~(Hc~@u@hv@zE~+vq@mc((~cei@l@z(~Hb@~@t@hItSn~rueHn~@j@i@q@q~==0){var~=Hp+(~){case ~()Hm~Hi@~break};~@n@sjm" ascii
    $s17 = ",677~HA,~9,3637,6665,3)~trueHVif~@mxEuz=14894;i~@w@zHL~}HC~==falseHi~HE7~788,8307,3094~==trueHi~;break;case ~I@lb@gN@kz()~,6995," ascii
    $s18 = "aO(k@g@m(g@gDbt,~HCfalse:~4667,7353,5376,313~H)@~@ihm@i@u=\"kr@zS\"};~H,(~(@pre@qgH_ ~Hafalse:if(~reak;case 1Hn~e@qg=\"vNuslx\";" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}