rule sig_20160503_16cbb711458f2eaf855fce87352e026c {
  meta:
    description = "datamaliciousorder - file 20160503_16cbb711458f2eaf855fce87352e026c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d040821d74b7bcc48a7f897e68f9f816f094cd35870d994f52b7f1b89155fc3"

  strings:
    $s1  = "eval((function(){var t=[75,88,79,70,71,81,74,82,66,85,60,89,90,80,94,86,72,76,65,87];var c=[];for(var z=0;z<t.length;z++)c[t[z]]" ascii
    $s2  = "ar z=0;z<a.length;z++)q=q.split(n+h.charAt(z)).join(String.fromCharCode(a[z]));return q.split(n+'!').join(n);})('function lzww(q" ascii
    $s3  = " 1Kr~b@xI=Kt};~KS@~))+Kf(~(2062,4190,~=KZ+(~}function ~{Kyw@gI~\"KY~))+Kw(~);Ka~04,1088,2~;return ~yIbl@iuu~;Ke~ 339:var~(Ko~()K" ascii
    $s4  = "KqKx=K,K%K#Kq@vwdsb@g@k=\"@pEay@wfr@p@l@n@hpke@st\".lengthKqKZ=K,K%K#X\"7===1){}KqMsDj=\"\"KqEmx=@x@t@z@y@ks.length;while(KZ@qEm" ascii
    $s5  = "eval((function(){var t=[75,88,79,70,71,81,74,82,66,85,60,89,90,80,94,86,72,76,65,87];var c=[];for(var z=0;z<t.length;z++)c[t[z]]" ascii
    $s6  = "(f+1)-32;l=f;f++;}else if(j==96){k=94*(t.length-32+p.charCodeAt(f+1))+p.charCodeAt(f+2)-32;l=f;f+=2;}else{continue;}if(u==null)u" ascii
    $s7  = "~\"yc@iqy\"X#7===f~tz@v=\"ryb@hKv@~(6233,5453,5946,~200};Katrue~K32~gv@x\"Kr@n@wIE~7351KC~Ka3){case ~K7v~Kyt@vj@yn=18~KC0:~s@i@x" ascii
    $s8  = "jjx\")~K@s~eak}X\"4==0){~y@ls@l=26283};~}KC~\"KC~==falseKo~ar h@iIlKs~ @ibdks@i@x=f~KH\"~KB0~alseX\"@ibdk~38;break;case~[@rb@l@y" ascii
    $s9  = ";break;case ~=@rb@l@yE(\"0~X$f@nc@w@v~Ke;;var~r @koqkt=137~=\"S@x@vlvr@g~3030,1825,1)~u@xqqx@g@o@s~1633,4467,23~5011,6665,3)~{ca" ascii
    $s10 = "~=Kt;~Ko@~switch(~){case ~;I@r@gN~Ks){~break};~CtMx@n(~\")Kq~luCbc@p~=0){var~g@mM@he~K}6=~@sca@oc~@mbcw@t~)]Kq~){X$~\"DNl@o~;X$~" ascii
    $s11 = "298,7437,3437,5K}xhb@v@nj){[(4712,1136,6067,1573,5265,4084,3082,1),rs@h][(4712,1136,6067,1573,5265,4084,3082,1)]()}}catch(r@vqMl" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}