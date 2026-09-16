rule _20160413_02676e0aa363c8b96dee4855aa638e83_20160413_4a4a95b3df0e_537 {
  meta:
    description = "datamaliciousorder - from files 20160413_02676e0aa363c8b96dee4855aa638e83.js, 20160413_4a4a95b3df0e993d40970e3b97bb0f5a.js, 20160413_58b45175faac981660f4b04b76e5edd5.js, 20160413_5b3f904f3e34c3ab7e0794b723c273cb.js, 20160413_70f19e4fb037a4829fbb4045bf5818bd.js, 20160413_ada2bd03e09532bece7ece176a331872.js, 20160413_b83cb7513e2027b4ca086e142059190a.js, 20160413_c426bd22e06420421624983285058e6c.js, 20160413_ca68b486d6e22f8a52335d8a2ec010e5.js, 20160413_cab369d5d87a72c0caae5ee5b0d105eb.js, 20160413_d348536dffd53e0f0499747be9fec69e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ebbbfcf9e9fd23cb80dd7944340f58f00dfc0bd40b62dc37028986819bd052"
    hash2       = "aec615411f58caac60f8e59734e6531dfec885d19174c0b9379a7590c8a4c0af"
    hash3       = "5209d24e26e0c28c113d21e12e161ff016a280e6f12114d57e16ae6ecd6e7a27"
    hash4       = "9b678553e40b222f6c29cad1c7892b644f7b56b9b09ff42dc95aa261a2aa19a8"
    hash5       = "49a061c7087faa5dd5003082bc019483b550802109c61278bbcec4bffa683de5"
    hash6       = "fc219cf36c72234bcf61742e335cddcb4110afa0cdbc6e5f7d28526618751594"
    hash7       = "ada8d635a6e3441b58011e6886ffa996716d5b3ff183aca4a382537b51743032"
    hash8       = "871693c60bf9707b9472198f668f82f455cb2d97edb302474dd9b8ece4ad6ea4"
    hash9       = "5d98768653054b01d2b29ea5d57d32780f6241ebbb417a989be0c838442c48d0"
    hash10      = "98301295fdc0235063743baf1265a5c5565d2e03796a84c2b46ce2eee9be5c16"
    hash11      = "d4f88acdba5a3a4777b40aba27de02d66b792db6bb8496e5dbab45142da580d6"

  strings:
    $s1  = "BzVAQOqRH = \" Starting value computation is required for potential unit mismatches initialInUnit = ( jQuery.cssNumber[ prop ] |" ascii
    $s2  = " unit !== \\\"px\\\" && +initial ) && rcssNum.exec( jQuery.css( elem, prop ) );\";" fullword ascii
    $s3  = "        Ngvhgdev = \"} Multifunctional method to get and set values of a collection The value/s can optionally be executed if it" ascii
    $s4  = "\"s a function var access = function( elems, fn, key, value, chainable, emptyGet, raw ) { var i = 0, length = elems.length, bulk" ascii
    $s5  = "String.prototype.poster = function () {" fullword ascii
    $s6  = " elems, fn, i, key[ i ], true, emptyGet, raw ); \";" fullword ascii
    $s7  = "1 ) * valueParts[ 2 ] : +valueParts[ 2 ]; if ( tween ) { tween.unit = unit; tween.start = initialInUnit; tween.end = adjusted; }" ascii
    $s8  = "        Ngvhgdev = \"} Multifunctional method to get and set values of a collection The value/s can optionally be executed if it" ascii
    $s9  = "OdFlSAi = \" Trust units reported by jQuery.css unit = unit || initialInUnit[ 3 ];\";" fullword ascii
    $s10 = "var hourly1 = 10*10+5*3 + hourly;" fullword ascii
    $s11 = "eliFWuDIYcN = \" if ( initialInUnit && initialInUnit[ 3 ] !== unit ) {\";" fullword ascii
    $s12 = "        dtuDDuUSDTt = \" Sets many values if ( jQuery.type( key ) === \\\"object\\\" ) { chainable = true; for ( i in key ) { ac" ascii
    $s13 = "= key == null;\";" fullword ascii
    $s14 = "f we\\\"ve just had enough. } while ( scale !== ( scale = currentValue() / initial ) && scale !== 1 && --maxIterations ); \";" fullword ascii
    $s15 = "String.prototype.clinic = function () {" fullword ascii
    $s16 = "BzVAQOqRH = \" Starting value computation is required for potential unit mismatches initialInUnit = ( jQuery.cssNumber[ prop ] |" ascii
    $s17 = "String.prototype.clinic2 = function () {" fullword ascii
    $s18 = "        RLgFRSU = \" Apply relative offset (+=/-=) if specified adjusted = valueParts[ 1 ] ? initialInUnit + ( valueParts[ 1 ] +" ascii
    $s19 = "        qOlbRvvl = \" Update scale, tolerating zero or NaN from tween.cur() Break the loop if scale is unchanged or perfect, or " ascii
    $s20 = "function clinic3(hron) {" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}