rule golang {
	strings:
				$string1 = "runtime.decoderune"
		$string2 = "golang"
	
	condition:
				$string1 or $string2
}