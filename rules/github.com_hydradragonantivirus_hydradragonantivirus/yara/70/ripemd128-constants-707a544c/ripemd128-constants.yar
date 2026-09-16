rule RIPEMD128_Constants {
	meta:
		author = "_pusher_"
		description = "Look for RIPEMD constants"
		date = "2017-05"
		version = "0.1"
	strings:
		$c0 = { 01234567 }
		$c1 = { 89ABCDEF }
		$c2 = { FEDCBA98 }
		$c3 = { 76543210 }
		$c4 = { 9979825A }
		$c5 = { A1EBD96E }

		$c6 = { DCBC1B8F }
		$c7 = { E68BA250 }
		$c8 = { 24D14D5C }
		$c9 = { F33E706D }

							condition:
		all of ($c*)
}