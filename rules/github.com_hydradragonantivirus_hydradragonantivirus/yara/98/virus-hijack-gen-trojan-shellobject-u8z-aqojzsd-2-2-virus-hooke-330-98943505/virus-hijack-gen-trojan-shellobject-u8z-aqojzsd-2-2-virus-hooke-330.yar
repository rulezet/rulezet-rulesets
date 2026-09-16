rule _Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_2_2_Virus_Hooke_330 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_2_2.vir, Virus.Hooker_Trojan.GenericKD.64731121.vir, Virus.Sysbot_Dropped.Generic.AutorunINF.Recex.1.1C7C33CC.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddd2c9145afaab6ae9d694619759a4d6569ae9345c64061e81160a1d2b93def"
    hash2       = "9633d4cd7b4f96fbe5e897823eecfe25c6f8b221ac7606874f8112c0c5229127"
    hash3       = "6607cf792b083f99fa7addb8d9c6c261cf597297b4d3be2d99429de6d4d956d5"

  strings:
    $s1  = "select rid, url, state, lastsynchronized, ttl, skiphours, skipdays, synchpriority, synchretries, flags, contentsize, cursyncetag" ascii
    $s2  = "ency><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.VC80.CRT\" version=\"8.0.50727.762\" proce" ascii
    $s3  = "select ifnull(ttloverride,ttl) +lastsynchronized from resources where state !=0 and ttl!=2147483647 order by lastsynchronized + " ascii
    $s4  = " and state != '0' and ttl!=2147483647 and ( lastsynchronized=0 or ( lastsynchronized + ifnull(ttloverride, ttl)  < ? ) ) and (sk" ascii
    $s5  = "select ifnull(ttloverride,ttl) +lastsynchronized from resources where state !=0 and ttl!=2147483647 order by lastsynchronized + " ascii
    $s6  = "select rid, url, state, lastsynchronized, ttl, skiphours, skipdays, synchpriority, synchretries, flags, contentsize, cursyncetag" ascii
    $s7  = "Mozilla/3.0 (compatible; Adobe Synchronizer 9.0)" fullword ascii
    $s8  = "ifnull(ttloverride,ttl) asc limit 1" fullword ascii
    $s9  = "create table resource_groups(id integer not null primary key autoincrement, urn text(512) not null, last_time integer not null d" ascii
    $s10 = "expected result for query select count(rid) > 0 from resources where state != 0 and ttl!=2147483647 and flags & ? == 0 " fullword ascii
    $s11 = "select count(rid) > 0 from resources where state != 0 and ttl!=2147483647 and flags & ? == 0 " fullword ascii
    $s12 = "select rid from resources where state!=0 and synchpriority < 50 and ttl!=2147483647 limit 1" fullword ascii
    $s13 = "nd state !=0 and ttl!=2147483647 order by synchpriority asc limit ?" fullword ascii
    $s14 = "iphours & (1 << ?)) = 0 and (skipdays & (1 << ?)) = 0 order by synchpriority asc limit ?" fullword ascii
    $s15 = "ault 0, changed integer not null default 0, track_def_flags integer not null default 0 ) " fullword ascii
    $s16 = "_nodes where rid=? and track_flags & ? != 0 )  and (decay_start = 0 or decay_start > ? )" fullword ascii
    $s17 = "update resource_groups set changed=1, decay_start=?, last_time=?, last_changed_rid=? where id in (select gid from resource_group" ascii
    $s18 = "update resource_groups set changed=1, decay_start=?, last_time=?, last_changed_rid=? where id in (select gid from resource_group" ascii
    $s19 = "_nodes where rid=? and track_flags & ? != 0 )  and decay_start !=?" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}