rule _20160323_734475f5a9d572b35dbe49262287247e_20160323_93c765e856eb_4097 {
  meta:
    description = "datamaliciousorder - from files 20160323_734475f5a9d572b35dbe49262287247e.js, 20160323_93c765e856eb93f1ae3d3e5e35c5b2a8.js, 20160323_949a84f8b38aa41b9ac9bd27f609c626.js, 20160323_a237c36a5c9d5a01b0900386120315fc.js, 20160323_e3df6f714d8a646b1f2c93512e2964ec.js, 20160323_f6929160c922fbcc82608480b84dd1ea.js, 20160324_14178d728b44bd85d21a418eebbe3910.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea22ffa95e7a05556a8944d06bd1122b60041cad6620371c45334887fac392a2"
    hash2       = "725734d7bcc0ebf99ddc287c3c500447dc1044c2a4dd255a75ba9f6b6808b176"
    hash3       = "3ac85cb37f327bf5e643a1594daa88f7cddc75797ca883edc6bcd357afe08389"
    hash4       = "7e6440d443c70168136bb5adbb7808f4d0a74f432750f67f30a40fd6dbf6af32"
    hash5       = "b41ca0f06e745aae5049c4a9eea520c962ed670b14ef1c48dc332862772b55a5"
    hash6       = "3e033d333baf9a571daf9d36a9150333c42ae6fed765d170e3cda08fa7a63cb9"
    hash7       = "28b2374c1f3267d1a952ff6845d881acef2f5f3300550d3a1e3681fc065294fb"

  strings:
    $s1 = "em ) { return siblings( elem.firstChild ); }, contents: function( elem ) { return jQuery.nodeName( elem, \\\"iframe\\\" ) ? elem" ascii
    $s2 = "tentDocument || elem.contentWindow.document : jQuery.merge( [], elem.childNodes ); } }, function( name, fn ) { jQuery.fn[ name ]" ascii
    $s3 = " = function( until, selector ) { var ret = jQuery.map( this, fn, until );\";" fullword ascii
    $s4 = " return dir( elem, \\\"nextSibling\\\", until ); }, prevUntil: function( elem, i, until ) { return dir( elem, \\\"previousSiblin" ascii
    $s5 = "ntil ); }, siblings: function( elem ) { return siblings( ( elem.parentNode || {} ).firstChild, elem ); }, children: function( el" ascii

  condition:
    (uint16(0) == 0x4555 and (all of them)
    ) or (all of them)
}