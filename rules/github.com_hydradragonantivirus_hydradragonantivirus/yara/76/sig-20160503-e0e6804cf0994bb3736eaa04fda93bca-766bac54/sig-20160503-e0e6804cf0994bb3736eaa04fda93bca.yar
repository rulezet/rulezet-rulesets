rule sig_20160503_e0e6804cf0994bb3736eaa04fda93bca {
  meta:
    description = "datamaliciousorder - file 20160503_e0e6804cf0994bb3736eaa04fda93bca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a15bf6018413e1a6e50429533e92c53eb18b24a1d7d9da252a3d2ae5c0469b52"

  strings:
    $s1  = "ar c=0;c<d.length;c++)f=f.split(l+k.charAt(c)).join(String.fromCharCode(d[c]));return f.split(l+'!').join(l);})('function @t@n@u" ascii
    $s2  = "k@iU^Ux@iwIi=29496}UGY\"U|5==\"T@z@ip\"Ummu@g=\"l@r@ld\"}UG231U|7===1){};break}U01:Uxv@irUnUGUU@kb@gol@w=\"@xw@i@rhU>360U|3UTUx@" ascii
    $s3  = "eval((function(){var z=[85,89,81,72,90,65,79,70,82,86,88,80,94,87,75,60,71,74,76,66];var y=[];for(var c=0;c<z.length;c++)y[z[c]]" ascii
    $s4  = "eval((function(){var z=[85,89,81,72,90,65,79,70,82,86,88,80,94,87,75,60,71,74,76,66];var y=[];for(var c=0;c<z.length;c++)y[z[c]]" ascii
    $s5  = "olfsb@ht=r@ib@n.length;while(UZ@volfsb@ht-(40U9)Um@qtEor@ww@gUPU!UuMw@j@wz=UO3U6Ukb@kpU\\'Mw@j@wzUkm@i@o@hfdU\\'UO40U9)UkyfdU\\'" ascii
    $s6  = "qz@u)UvUqUY09Uz44000055010\")]==(84,6253,6789,5695,200)){switch(3Ui1:Ux@qw@p@iMDd=39820Uvqw@p@iMDd==\"hSe\"){}UGfY\\'U|5U7gykUn}" ascii
    $s7  = "@gvyC@w()~p@qCr=\"@zx@~}function ~UZ+(~=(4383,550~0:Ux@oDa~\"UW~))+v@kE((~=Un){~true:Ux~xla=60555~;return ~;break};~[e@nc(\"0~pC" ascii
    $s8  = "@q@iy(q@kEt,@wbriS){switch(@wbriSUi0:Ux@im@y@q=\"luD@mnU>\"SNdDw@p\":Uxd@l@u@uN@uUnUG492:Uxk@nT@niI=Y\";break}UW1UNs@jndra(o@t@m" ascii
    $s9  = "(a+1)-32;p=a;a++;}else if(o==96){t=94*(z.length-32+n.charCodeAt(a+1))+n.charCodeAt(a+2)-32;p=a;a+=2;}else{continue;}if(u==null)u" ascii
    $s10 = "cyv~=e@nc(\"0~;switch(~(Uk@~==Y\"){~Uh@~@zw@uj@m~9,2897,3~6,1723,8~8768,268~M@olh=tr~vhn@n@zl~kjo=Y\"~(@Y2Ei~(Um~){case ~fMh@l@i" ascii
    $s11 = "@yd~e U4@~ya@o=\"kN@ic\"UyvN~@j@uj=\"@jS@jMNh@j\"~=trueUG~U2{~{Ux@weC@kq=fals~e}U\\\\7){case~U\\\\5){case ~iU5i~if(@ik@pk@wM==0)" ascii
    $s12 = "4925,4435,49Y&12,1297,7706,2902,3788,1),Caac@xa][(4925,4435,49Y&12,1297,7706,2902,3788,1)]()}}else {UxDuCqj@nS=\"SN@u@p\"}}catch" ascii
    $s13 = "5~ru@o\"};break}~ UH~Ei=\"@uId@ouE\"~ueUyvM@olh=~z=\"@o@glu@me\"~S@rzn=\"lfws\";~;break;case ~yp@uvdp=3521~r td@m=22344~UN@~brea" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}