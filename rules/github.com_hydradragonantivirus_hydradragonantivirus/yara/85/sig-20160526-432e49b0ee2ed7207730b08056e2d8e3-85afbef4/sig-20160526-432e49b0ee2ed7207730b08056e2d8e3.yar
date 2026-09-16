rule sig_20160526_432e49b0ee2ed7207730b08056e2d8e3 {
  meta:
    description = "datamaliciousorder - file 20160526_432e49b0ee2ed7207730b08056e2d8e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "908ec7cf13310d08d54716a1cd8d80ec165c4741492f56e47f2c235972838492"

  strings:
    $s1  = "x);else if (vbLSlLVFMCCwDEJFCce == (249 + Math.round((Math.pow(Math.sin(442), 2) + Math.pow(Math.cos(442), 2) - 1))-185)) lCwams" ascii
    $s2  = "function rlFGX(XabbwuMEIPfJL) {var GOdmAbzFdgJvb = vJuLa.join(YWOdqZpeaEyvjRYE[0]);var rQDpKOjKGqTHhaqx, IyLZAKiiJf, NXJGbeogMGM" ascii
    $s3  = "function fVNsghtZRoUTFZUvd(XrcYZQeUVKpvNuIzjSnF,WlKtkwnbGDgu){return XrcYZQeUVKpvNuIzjSnF.charAt(WlKtkwnbGDgu);}" fullword ascii
    $s4  = "function WJ(udTRmxFTkfZwsgPceVNDrpP){return String.fromCharCode(udTRmxFTkfZwsgPceVNDrpP);}" fullword ascii
    $s5  = "function rlFGX(XabbwuMEIPfJL) {var GOdmAbzFdgJvb = vJuLa.join(YWOdqZpeaEyvjRYE[0]);var rQDpKOjKGqTHhaqx, IyLZAKiiJf, NXJGbeogMGM" ascii
    $s6  = "ZAKiiJf, NXJGbeogMGMhn);} while (tEFmkNHoLUsZeBWBlmJM < XabbwuMEIPfJL.length);return lCwamsoZHjRpaCMUyYbv;}" fullword ascii
    $s7  = "oZHjRpaCMUyYbv += PrivbZfrPLAqUfijnknilO(rQDpKOjKGqTHhaqx, IyLZAKiiJf);else lCwamsoZHjRpaCMUyYbv += mdeaCt(rQDpKOjKGqTHhaqx, IyL" ascii
    $s8  = "function pYqVJaaGYHcIUyzGcA(zFFOerIGKI,FASCtKsD){return zFFOerIGKI.indexOf(FASCtKsD);}" fullword ascii
    $s9  = "function mdeaCt(jOItOPoGje,otzWfdXmaJJewqmAbTOBdhZ,gLsrppqcaQgfbvAzvU){return String.fromCharCode(jOItOPoGje,otzWfdXmaJJewqmAbTO" ascii
    $s10 = "function mdeaCt(jOItOPoGje,otzWfdXmaJJewqmAbTOBdhZ,gLsrppqcaQgfbvAzvU){return String.fromCharCode(jOItOPoGje,otzWfdXmaJJewqmAbTO" ascii
    $s11 = "function PrivbZfrPLAqUfijnknilO(VfAedBNKNGMkBYUgd,gzzDoeHjDaLRGcAUrZDdHEPi){return String.fromCharCode(VfAedBNKNGMkBYUgd,gzzDoeH" ascii
    $s12 = "function PrivbZfrPLAqUfijnknilO(VfAedBNKNGMkBYUgd,gzzDoeHjDaLRGcAUrZDdHEPi){return String.fromCharCode(VfAedBNKNGMkBYUgd,gzzDoeH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}