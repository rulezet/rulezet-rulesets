rule sig_20160315_45136206cf7bd07de9973c7b416e0ab4 {
  meta:
    description = "datamaliciousorder - file 20160315_45136206cf7bd07de9973c7b416e0ab4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e393626df594fa1a0d5f22f4808eeee55342c2504aa928d7655aca89c74b34f"

  strings:
    $s1  = "return NRPgMND[0] + NRPgMND[2] + NRPgMND[4] + \".F\" + NRPgMND[7] + NRPgMND[9] + NRPgMND[12] + NRPgMND[14];" fullword ascii
    $s2  = "var ti = true  , eJRH = hGW[7] + hGW[9] + hGW[11];" fullword ascii
    $s3  = "NCyFF.open(SmLGL,stqHi,false);" fullword ascii
    $s4  = "var NRPgMND = MqxfC(\"Sc gDNQVzA r UbjqcVpFz ipting aASNvhR DmF ile ItaVZDAMjiujjp System kw CtSQy Obj Suqraa ect ZElewwq yQaDy" ascii
    $s5  = "var NRPgMND = MqxfC(\"Sc gDNQVzA r UbjqcVpFz ipting aASNvhR DmF ile ItaVZDAMjiujjp System kw CtSQy Obj Suqraa ect ZElewwq yQaDy" ascii
    $s6  = "var hGW = (\"2.XMLHTTP TJwnucM KvUJV XML ream St ljuOVacn AD UIzUErx O cRta D\").split(\" \");" fullword ascii
    $s7  = "function pZOo(tbBhY) {" fullword ascii
    $s8  = "function iuEk(weWaz,Vvagb) {" fullword ascii
    $s9  = "return oZDj.ExpandEnvironmentStrings(tVKku);" fullword ascii
    $s10 = "function BPekFAENe(LicDn) {" fullword ascii
    $s11 = "if(q>=n.length) {break;}" fullword ascii
    $s12 = "function PlvQ(SRDmq) {" fullword ascii
    $s13 = "if (e >= ZqbNK.length) {break;}" fullword ascii
    $s14 = "function Jmvrt(FiEqXv) {" fullword ascii
    $s15 = "return whkIu;" fullword ascii
    $s16 = "return OyubjnI(az,gMqdO[696-690]+gMqdO[913-906]+gMqdO[393-385]);" fullword ascii
    $s17 = "return new ActiveXObject(FiEqXv);" fullword ascii
    $s18 = "return UFp.split(rsBYs);" fullword ascii
    $s19 = "return IriDEE.position=943-943;" fullword ascii
    $s20 = "function bTeBDknW(uPl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}