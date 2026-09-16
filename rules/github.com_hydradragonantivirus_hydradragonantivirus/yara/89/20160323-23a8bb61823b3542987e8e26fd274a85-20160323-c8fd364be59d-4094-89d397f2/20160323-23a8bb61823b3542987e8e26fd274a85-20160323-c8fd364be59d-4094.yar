rule _20160323_23a8bb61823b3542987e8e26fd274a85_20160323_c8fd364be59d_4094 {
  meta:
    description = "datamaliciousorder - from files 20160323_23a8bb61823b3542987e8e26fd274a85.js, 20160323_c8fd364be59d5d33d25729d94e5ac7b4.js, 20160323_d12b0e4df473ea93a9fe09042074fded.js, 20160323_d875596b827f99af54b9c2b5c4e2b7a7.js, 20160323_fd03b9ead6ae07ff231884cfee11ff23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c06aaf8faf43d59ff710554e5b6c8b76d1837c2e1db9e17f45413c8716a888b"
    hash2       = "f27c8fd3403da10bc42176fc6de1d98d07fe180e7f61f1cd8c4836c47511d7a4"
    hash3       = "44c9ae78b743e01f05ece8f8b5636a3769bf24d31856f82f980ea5a42c6c28be"
    hash4       = "1ccb7ec993e724e8ddefc4386c6a91de657874fe64be22d7732a366bc3a2b21c"
    hash5       = "aa4f6b40da27a26c43433cc7099b0817a3303edda718c67729c225050806637f"

  strings:
    $s1 = " { return siblings( elem.firstChild ); }, contents: function( elem ) { return jQuery.nodeName( elem, \\\"iframe\\\" ) ? elem.con" ascii
    $s2 = "Document || elem.contentWindow.document : jQuery.merge( [], elem.childNodes ); } }, function( name, fn ) { jQuery.fn[ name ] = f" ascii
    $s3 = "unction( until, selector ) { var ret = jQuery.map( this, fn, until );\";" fullword ascii
    $s4 = " ); }, siblings: function( elem ) { return siblings( ( elem.parentNode || {} ).firstChild, elem ); }, children: function( elem )" ascii
    $s5 = "urn dir( elem, \\\"nextSibling\\\", until ); }, prevUntil: function( elem, i, until ) { return dir( elem, \\\"previousSibling" ascii

  condition:
    (uint16(0) == 0x4555 and (all of them)
    ) or (all of them)
}