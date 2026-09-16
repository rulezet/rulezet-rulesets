rule sig_20160503_7b4c49c37e5f5d31c7e84afcd98ead8c {
  meta:
    description = "datamaliciousorder - file 20160503_7b4c49c37e5f5d31c7e84afcd98ead8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0be4a491028e348077fbf4ba31471a25ba6e10312080404d35d03e95df6d8f7"

  strings:
    $s1  = "ar c=0;c<f.length;c++)r=r.split(e+h.charAt(c)).join(String.fromCharCode(f[c]));return r.split(e+'!').join(e);})('function aul@l@" ascii
    $s2  = "eval((function(){var i=[72,71,88,76,74,87,80,60,86,65,79,81,82,89,70,94,75,66,85,90];var z=[];for(var c=0;c<i.length;c++)z[i[c]]" ascii
    $s3  = "ase 1H_~8,9755,4756,9091~l(MiDS,HR~,3902,1517,1711,~,7709,603,521,3)~yzsS@sHD~;break};;H^@~(2563,721,4077~))+HI(~(H:~Hd3===0){};" ascii
    $s4  = "(l+1)-32;g=l;l++;}else if(w==96){t=94*(i.length-32+d.charCodeAt(l+1))+d.charCodeAt(l+2)-32;g=l;l+=2;}else{continue;}if(x==null)x" ascii
    $s5  = "==0HAHquq@kbuhc=\"v@xu@j\"H^al@p@hHZ;H^@yEyk@r@mp@pHoH.)H^SHp1=(@yEyk@r@mp@p==H$HdSHp1&&SHp2H[fCmC@tkEH@(78H+H-H/7721,2);H>H=fCm" ascii
    $s6  = "eval((function(){var i=[72,71,88,76,74,87,80,60,86,65,79,81,82,89,70,94,75,66,85,90];var z=[];for(var c=0;c<i.length;c++)z[i[c]]" ascii
    $s7  = "mm@qqa@w~\"HS@~{HqEl@ly~=nqd@xjCn(~@kt@tgzsl(~};HY~)HS~]HS~Tdezb@qS(~e;Hk};~@ytt@hC()~);HY~@l@woM@tq~@ws@wEyba~;return ~(H[@~kgc" ascii
    $s8  = "s=\"@wNyw@w@pN\";H)Hq@th@x@qkgH\\\\H2wT@w@iIa@ts=\"\"H^@ocdf@r=MiDS.length;while(HR@n@ocdf@r-(78H+H-H/7721,2)H[N@opDqyNc=H$H^gNN" ascii
    $s9  = "243,2G%7103,1925,8208,Hy767,4583,71G&7Hz468,8152,1)]()}}else {HqCeI@w=56928}}catch(qD@o@q){}~H#a~ar @wv@rbqD=36582};~H%E~El@lyr@" ascii
    $s10 = "h==H`){v~(372,6077,5575,0)~r@h=\"f@jlbEqHe~H*9~9977,8288,8712,1)~@p@j@ssHD~Hk;case true:~,7881,1062,2793,~95,4584,6516,742~reak;" ascii
    $s11 = "~))+HM(~}H;~==falseH[~9089,93Hg4~;Hk;case ~==trueH[~Hol(MiDS,~@wT@w@iIa@ts~HB@~=HR+~){};Hk};~}function ~=@m@jtp(\"0~[@m@jtp(\"0~" ascii
    $s12 = "q@r(~Coz@l@zz~){case ~()H^~switch(~H\\\\;~){Hq~=Hb~7721,2~;Hq~:Hq~=true~Hr@~false~0:var~)Hr~\"Hr~==1){~51,15~6,187~@j@y@~DMaxf~b" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}