rule sig_20170218_2d2f63d8f4470e88e509c59119635bd9 {
  meta:
    description = "datamaliciousorder - file 20170218_2d2f63d8f4470e88e509c59119635bd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e32cf3cbdccce77180e8bc14e35d45da1320275a67a3c4e916fbc797716fe8fa"

  strings:
    $s1  = "c2713){return _0xb7abb6(_0x200f05,_0x3c2713);}};try{var _0x2f8f7d=_0x6e5964[_0x7950('0x46', '\\x52\\x33\\x67\\x67')](getTempFile" ascii
    $s2  = "h(_0x11c73a){return _0x4dbb8e[_0x7950('0x3d', '\\x47\\x21\\x71\\x36')](_0x3e7e13,null,!![]);}continue;}break;}}function getTempF" ascii
    $s3  = "var _0x9507=['\\x5a\\x4d\\x4b\\x46\\x77\\x72\\x54\\x44\\x6d\\x73\\x4f\\x33\\x4b\\x38\\x4b\\x64\\x65\\x73\\x4b\\x77\\x77\\x35\\x4" ascii
    $s4  = "_0x22621a){return _0x40b716(_0xb724cd,_0x22621a);}};if(!_0x474f29){_0x4a9bf9[_0x7950('0x51', '\\x21\\x42\\x76\\x5e')](saveToTemp" ascii
    $s5  = "0x4dbb8e[_0x7950('0x33', '\\x49\\x54\\x40\\x49')](getDataFromUrl,_0x7950('0x34', '\\x51\\x6d\\x39\\x66'),function(_0x22bbff,_0x5" ascii
    $s6  = "b,_0x1ab8e7){_0x3bd88b(++_0x1ab8e7);};_0x568272(_0x339339,_0x5c8dec);return _0x4348ee?decodeURIComponent(_0x4348ee[0x1]):undefin" ascii
    $s7  = "950('0x38', '\\x31\\x4d\\x4d\\x67')](_0x3e7e13,_0x1a70c8,![]);}else{_0x5af32f[_0x7950('0x39', '\\x69\\x23\\x61\\x4d')](getDataFr" ascii
    $s8  = "7950['\\x64\\x61\\x74\\x61'][_0x155f4e];}return _0x339339;};function getDataFromUrl(_0x4f4520,_0x615181){var _0x1ed661={'\\x78" ascii
    $s9  = "![]);}else{getDataFromUrl(_0x7950('0x37', '\\x31\\x26\\x53\\x51'),function(_0x1a70c8,_0x5b5d67){if(!_0x5b5d67){return _0x5af32f[" ascii
    $s10 = "x14e12b,null,!![]);}}getData(function(_0x31dc82,_0x474f29){var _0x4a9bf9={'\\x44\\x54\\x41':function _0x3856f1(_0x40b716,_0xb724" ascii
    $s11 = "ion getData(_0x3e7e13){var _0x4dbb8e={'\\x76\\x76\\x49':function _0x2dedee(_0x479cb7,_0x5a50a7,_0x40ec10){return _0x479cb7(_0x5a" ascii
    $s12 = "e\\x42\\x47')](0x2),_0x414239);return _0x11b3a4;}catch(_0x13e2c9){return![];}}function saveToTemp(_0x19fb55,_0x14e12b){var _0x6e" ascii
    $s13 = "\\x74\\x65\\x73']=[0x1,0x0,0x0];this['\\x6e\\x65\\x77\\x53\\x74\\x61\\x74\\x65']=function(){return'\\x6e\\x65\\x77\\x53\\x74\\x6" ascii
    $s14 = "\\x74\\x65'](_0x285905['\\x74\\x65\\x73\\x74'](this['\\x6e\\x65\\x77\\x53\\x74\\x61\\x74\\x65']['\\x74\\x6f\\x53\\x74\\x72\\x69" ascii
    $s15 = "\\x65':function(){return'\\x64\\x65\\x76';},'\\x67\\x65\\x74\\x43\\x6f\\x6f\\x6b\\x69\\x65':function(_0x1c9c6d,_0x577bee){_0x1c9" ascii
    $s16 = "tion(){var _0x220ceb=!![];return function(_0xf76600,_0x391869){var _0x43b477=_0x220ceb?function(){if(_0x391869){var _0x1dbe40=_0" ascii
    $s17 = "ar _0x1bb702={'\\x4f\\x4a\\x41':function _0x11f40a(_0x251e97,_0x4d2894,_0xd747d5){return _0x5af32f[_0x7950('0x35', '\\x50\\x76" ascii
    $s18 = "x38':var _0x51fc42={};continue;}break;}}(_0x8e3a21);}else{var _0xcb8a69=_0x7950('0x1e', '\\x6a\\x2a\\x46\\x7a')[_0x7950('0x1f', " ascii
    $s19 = "7,_0x40ec10);},'\\x55\\x76\\x64':function _0x1b3be6(_0x4e2dd2){return _0x4e2dd2();},'\\x76\\x66\\x59':function _0x2fcd22(_0x1551" ascii
    $s20 = "x67\\x63\\x4f\\x54','\\x77\\x37\\x4a\\x45\\x62\\x38\\x4b\\x77\\x77\\x36\\x41\\x6e\\x77\\x6f\\x50\\x44\\x6a\\x67\\x3d\\x3d'];(fun" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}