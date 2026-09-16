rule warning_embedded_flash {
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 5
		revision = "1"
		date = "July 29 2015"
		author = "@tylabs"
		release = "lite"
		copyright = "QuickSand.io (c) Copyright 2015. All rights reserved."
		tlp = "white"
		sigtype = "cryptam_exploit"
		desc = "Embedded Flash data"
	strings:
		$cws = {66556655??????00435753}
		$fws = {66556655??????00465753}
		$zws = {66556655??????005a5753}
		$control = "CONTROL ShockwaveFlash.ShockwaveFlash"
		$jit = {076A69745F656767}
		$generic = "ShockwaveFlash.ShockwaveFlash."
		$genericw = "ShockwaveFlash" wide
		$generich = "53686F636B77617665466C6173682E53686F636B77617665466C6173682E"

	condition:
            1 of them
}