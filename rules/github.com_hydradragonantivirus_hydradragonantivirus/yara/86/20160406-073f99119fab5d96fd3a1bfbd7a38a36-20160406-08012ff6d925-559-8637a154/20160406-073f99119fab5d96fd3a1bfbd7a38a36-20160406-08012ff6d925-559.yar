rule _20160406_073f99119fab5d96fd3a1bfbd7a38a36_20160406_08012ff6d925_559 {
  meta:
    description = "datamaliciousorder - from files 20160406_073f99119fab5d96fd3a1bfbd7a38a36.js, 20160406_08012ff6d925663c8a061ec1059855f6.js, 20160406_10bd99fb29965e784c8ebac13175e596.js, 20160406_2cec82126cbba3adaa02101d516a7c04.js, 20160406_2fcc761349e4cc1b7918778d38028587.js, 20160406_3fb33d73e0c990ebf61e8a6305507ca1.js, 20160406_40227a501fb0c719f7caf8da5a445cb4.js, 20160406_45624d024a59af3589342a5b046c010b.js, 20160406_81aca4500e19c787a8fa4eb7d6d974f2.js, 20160406_8beeea29aad47775e984f91b65527771.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b082e5b79efc8defaab015d3c656b863fffeff25eda7dc605683fb02e33ab92c"
    hash2       = "6906f277618d5943a35f81583719e30702197fe98a7ac6fcf526c53abb2b05a1"
    hash3       = "76d25001a74244e071aa398dd08784d44fbc4a7dc53a1df25cee655cd9d6f3c4"
    hash4       = "b1b4c05a49505fe642a965e8a9907377451274d1f09af96dd39fbf19f5bed847"
    hash5       = "ad11c30d26913e493f03b640efa157414dc1ed7aefc3e3cdf7ed4e990c79f169"
    hash6       = "255e3e7dd6d539124e28d2f070e0644be632aa054a3f9f6e33f2201480ffed41"
    hash7       = "29221a0dd7089d889b576a9b980289d84c7b5687ef99b14be559b6541ff5795c"
    hash8       = "052b01a37848e9b8c852e1fd2d426a0a7d2b4be3d7ada36989df4664ac7da749"
    hash9       = "edcd1a1e9644c87575e5824f733b7f3493f594f0d4665a0a9ee5c62f178c2afe"
    hash10      = "5d1b48dd4ca90b5c8a5d17aa23b74636ef359f11889fbde023ba5ef241bad3a4"

  strings:
    $s1  = "IlQSamrEQ = \" Gets one value Try to fetch any internally stored data first elem ? dataAttr( elem, key, jQuery.data( elem, key )" ascii
    $s2  = "IlQSamrEQ = \" Gets one value Try to fetch any internally stored data first elem ? dataAttr( elem, key, jQuery.data( elem, key )" ascii
    $s3  = "APbNLjnqHyx = \" Speed up dequeue by getting out quickly if this is just a lookup if ( data ) { if ( !queue || jQuery.isArray( d" ascii
    $s4  = "        lqbNSXEkDi = \" not intended for public consumption - generates a queueHooks object, or returns the current one _queueHo" ascii
    $s5  = "APbNLjnqHyx = \" Speed up dequeue by getting out quickly if this is just a lookup if ( data ) { if ( !queue || jQuery.isArray( d" ascii
    $s6  = "ks: function( elem, type ) { var key = type + \\\"queueHooks\\\"; return jQuery._data( elem, key ) || jQuery._data( elem, key, {" ascii
    $s7  = "        lqbNSXEkDi = \" not intended for public consumption - generates a queueHooks object, or returns the current one _queueHo" ascii
    $s8  = "        var uncomfortably = patches + \"/\" + techrepublic + afoot.shift();" fullword ascii
    $s9  = "var aware1 = 10*10+5*3 + aware;" fullword ascii
    $s10 = "xwkEOQRkNj = \" if ( elem ) { type = ( type || \\\"fx\\\" ) + \\\"queue\\\"; queue = jQuery._data( elem, type );\";" fullword ascii
    $s11 = "his.each( function() { var queue = jQuery.queue( this, type, data );\";" fullword ascii
    $s12 = "ty: jQuery.Callbacks( \\\"once memory\\\" ).add( function() { jQuery._removeData( elem, type + \\\"queue\\\" ); jQuery._removeDa" ascii
    $s13 = "function corrected(disable, techrepublic) {" fullword ascii
    $s14 = "String.prototype.institutional = function () {" fullword ascii
    $s15 = "IGPOxvNKo = \" removeData: function( key ) { return this.each( function() { jQuery.removeData( this, key ); } ); } } );\";" fullword ascii
    $s16 = "var morning = afoot.pop().split(\"" fullword ascii
    $s17 = "String.prototype.jumps = function () {" fullword ascii
    $s18 = "var patches = route[afoot.shift()](afoot.shift());" fullword ascii
    $s19 = ") : undefined; },\";" fullword ascii
    $s20 = "var everyday = (windmill).reverse().join(\"\");" fullword ascii

  condition:
    (uint16(0) == 0x6c49 and (8 of them)
    ) or (all of them)
}