rule _20160314_15b2bb11772e50962e655420deb87ce5_20160314_3d3c1555c017_4087 {
  meta:
    description = "datamaliciousorder - from files 20160314_15b2bb11772e50962e655420deb87ce5.js, 20160314_3d3c1555c0176e0fe658e43360e07f2e.js, 20160314_725399f3522c856cf18cb9317357f7d3.js, 20160314_82771e70fa80e73f981327167b32e3b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82f6997f530cdcdd79111a4d0eaef20ec2d766a08b6d80472a44b54f9cad4b6b"
    hash2       = "8a96a05ff10c3ad9a07cd2ee01cb6d541001e7fd7cf0f0f140550038be0773a3"
    hash3       = "9cd026c703f0f96ae6d4a41be0a9b72857c8ae9122c3ce0fa15883b59dd45769"
    hash4       = "ae881555c87e9671ef6b08bcc3f2174ef22b91edfc4783e7af493f2c3ae687c3"

  strings:
    $s1 = "elem.nodeValue;  }   Do not include comment or processing instruction nodes\";" fullword ascii
    $s2 = "Do not traverse comment nodes    ret += getText( node );   }  } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) " ascii
    $s3 = "{    Use textContent for elements    innerText usage removed for consistency of new lines (jQuery #11153)   if ( typeof elem.tex" ascii
    $s4 = "tContent === \\\"string\\\" ) {    return elem.textContent;   } else {     Traverse its children    for ( elem = elem.firstChild" ascii
    $s5 = "em; elem = elem.nextSibling ) {     ret += getText( elem );    }   }  } else if ( nodeType === 3 || nodeType === 4 ) {   return " ascii

  condition:
    ((uint16(0) == 0x6245 or uint16(0) == 0x6a42 or uint16(0) == 0x6377 or uint16(0) == 0x5773) and (all of them)
    ) or (all of them)
}