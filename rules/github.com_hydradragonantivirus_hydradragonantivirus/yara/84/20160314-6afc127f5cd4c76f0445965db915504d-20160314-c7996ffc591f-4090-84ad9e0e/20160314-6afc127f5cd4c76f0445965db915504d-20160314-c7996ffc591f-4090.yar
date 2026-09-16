rule _20160314_6afc127f5cd4c76f0445965db915504d_20160314_c7996ffc591f_4090 {
  meta:
    description = "datamaliciousorder - from files 20160314_6afc127f5cd4c76f0445965db915504d.js, 20160314_c7996ffc591fb34e13f31800fc329bac.js, 20160314_d22461ccedd5cd5f1401b8b87a0d3764.js, 20160314_eef2a18bd8524496dabd2d8bf6b2270e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcd8a86012b4c6091cca0aabccf3d876ac2dcdd4adb2ffeb859261c5a761af18"
    hash2       = "a4ff03ad07561ba90067f144a78eefd52d242b3b86285e6ac8b4a533c6e1ea0f"
    hash3       = "c990782a21b774fb25da6916163afb3d055ffa047c40eb846b37692545fcf53f"
    hash4       = "f6e6fe7babcfe5113267a284c27cd3e5db5a86b2b64e84e3dee5008c7d7da326"

  strings:
    $s1 = "em.nodeValue;  }   Do not include comment or processing instruction nodes\";" fullword ascii
    $s2 = " not traverse comment nodes    ret += getText( node );   }  } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 ) { " ascii
    $s3 = "   Use textContent for elements    innerText usage removed for consistency of new lines (jQuery #11153)   if ( typeof elem.textC" ascii
    $s4 = "ontent === \\\"string\\\" ) {    return elem.textContent;   } else {     Traverse its children    for ( elem = elem.firstChild; " ascii
    $s5 = "; elem = elem.nextSibling ) {     ret += getText( elem );    }   }  } else if ( nodeType === 3 || nodeType === 4 ) {   return el" ascii

  condition:
    ((uint16(0) == 0x6469 or uint16(0) == 0x5655 or uint16(0) == 0x5857 or uint16(0) == 0x4168) and (all of them)
    ) or (all of them)
}