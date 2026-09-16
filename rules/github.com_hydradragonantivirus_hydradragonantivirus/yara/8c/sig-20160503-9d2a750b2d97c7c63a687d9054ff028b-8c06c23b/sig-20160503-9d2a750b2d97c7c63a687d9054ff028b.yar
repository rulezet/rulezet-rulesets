rule sig_20160503_9d2a750b2d97c7c63a687d9054ff028b {
  meta:
    description = "datamaliciousorder - file 20160503_9d2a750b2d97c7c63a687d9054ff028b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a59124eb78e934bbc243a5703b14d166d92788cd7dc41a084215d2de1a75c9b"

  strings:
    $s1  = "ar m=0;m<y.length;m++)c=c.split(p+s.charAt(m)).join(String.fromCharCode(y[m]));return c.split(p+'!').join(p);})('function @ux@te" ascii
    $s2  = "eval((function(){var h=[60,71,86,66,90,70,72,65,85,81,88,80,87,79,74,89,94,76,75,82];var z=[];for(var m=0;m<h.length;m++)z[h[m]]" ascii
    $s3  = "\\\\;<m<S=\"\"<dz@t@leuhdd=@qmaespC@k.length;while(<N@g@z@t@leuhdd-(21<G<><@G#<A<9<c@vv@j@quw=<2<#<mwdd@tDl<H<=)<mwNj@y@p@m=v@<!" ascii
    $s4  = "<Q7<Z\"@tdl\"<x6<P<q@rMNT=37408<5\"@rayMf\"<x1==\"ySnv\"){<599:<q@havE@q=61103<O;<mnSjr= new @teo(dfegg)<Q4<Z<ft@kwvj<(\"DIdmtx" ascii
    $s5  = "{switch(<n<Z<k<q@oDw@xu@rb=46694<;<kif(ka@lh@k@l===123<c@qap=\"@jdmN\"<5<s:<qhl@v@uxm@x=87806<rhl@v@uxm@x===1<c@q@o@jnc=\"ro@zc" ascii
    $s6  = "@h@le){switch(0<Z\"@tto@rg\":<qThqD@s=\"bgM@zS<pThqD@s==722<c@zu@y@j=<n};br< mky<(289:<qy@k@tS@upb=45093<ry@k@tS@upb==\"@pcvf\"<" ascii
    $s7  = "(u+1)-32;n=u;u++;}else if(q==96){x=94*(h.length-32+f.charCodeAt(u+1))+f.charCodeAt(u+2)-32;n=u;u+=2;}else{continue;}if(o==null)o" ascii
    $s8  = "t=80059<mn@twc=\"@xh@u@i@l\"<5\"@yfughS\":<qswxS@h=fals<.<n<Z<k<q@yCw=72183<;1:<q@pnrog@vI=\"Esd@vzl@z\"<;<fSffv@j=<s;break}<CcS" ascii
    $s9  = "eval((function(){var h=[60,71,86,66,90,70,72,65,85,81,88,80,87,79,74,89,94,76,75,82];var z=[];for(var m=0;m<h.length;m++)z[h[m]]" ascii
    $s10 = "3,78~=<N+~@<X7~74549<m~ 1:<qMn~;return ~(<[~b@mDs@nh~;bre<w~==<s){~;switch(~){}<m~SCDocx@k~26,752,3~<_2~<mvd@~a@prscEM~j@mo@xE=~" ascii
    $s11 = "(<c~){case ~)<d~=<n;~Mz@zqeT~y@mw@zE~5256,15~<i5~=@oh@q(~)]<m~){<q~<m@~();var~0:<q~;jz@pb~,4060,~0,868,~3<{0~<n:~bmoum(~;<q~fals" ascii
    $s12 = "@y@y=tru~;break;case ~<C@~(120,5132,1~63,3964,744~<G6~6,4147,7333~3,2404,5799~p@l@z=<s;~}function ~))+<l(~Eat@ly@o@u~\"<L@~71,66" ascii
    $s13 = "106,6256,464<h8608G\"2,9893,1)]()}}catch(sj@jf@oi){}~eak;case <kvar ~nv@moIf(@qmaespC@k,~alse){<5~0,5210,7700,2526,0)~tz@kdE@o\"" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}