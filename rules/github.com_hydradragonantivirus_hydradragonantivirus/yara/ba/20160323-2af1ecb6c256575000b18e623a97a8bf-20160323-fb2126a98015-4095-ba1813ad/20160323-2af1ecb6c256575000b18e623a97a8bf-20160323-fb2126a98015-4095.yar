rule _20160323_2af1ecb6c256575000b18e623a97a8bf_20160323_fb2126a98015_4095 {
  meta:
    description = "datamaliciousorder - from files 20160323_2af1ecb6c256575000b18e623a97a8bf.js, 20160323_fb2126a9801595404812e8b9c9ac98f8.js, 20160324_c35c970cd71a498452a33d2947c95a2a.js, 20160324_cba385abcad9e59f91a075a5340297d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1232d6c1f7f717503f5da77b02592ca82aaaa96f1f1a8228a136b26355bd6bc"
    hash2       = "69ce5845bd8210f3805ecdc048b301b771845856c65c30c4e59a32137b343fdb"
    hash3       = "ecebed24720fc4760b49919bd34a887a503eec42295536e272496192bb8fc061"
    hash4       = "ef00a4a2601c8c6f8a166fbe2589cc2cc5f07073f1cca08ad8431b93c4b80bab"

  strings:
    $s1 = " ) { return siblings( elem.firstChild ); }, contents: function( elem ) { return jQuery.nodeName( elem, \\\"iframe\\\" ) ? elem.c" ascii
    $s2 = "ntDocument || elem.contentWindow.document : jQuery.merge( [], elem.childNodes ); } }, function( name, fn ) { jQuery.fn[ name ] =" ascii
    $s3 = " function( until, selector ) { var ret = jQuery.map( this, fn, until );\";" fullword ascii
    $s4 = "eturn dir( elem, \\\"nextSibling\\\", until ); }, prevUntil: function( elem, i, until ) { return dir( elem, \\\"previousSibling" ascii
    $s5 = "il ); }, siblings: function( elem ) { return siblings( ( elem.parentNode || {} ).firstChild, elem ); }, children: function( elem" ascii

  condition:
    (uint16(0) == 0x4555 and (all of them)
    ) or (all of them)
}