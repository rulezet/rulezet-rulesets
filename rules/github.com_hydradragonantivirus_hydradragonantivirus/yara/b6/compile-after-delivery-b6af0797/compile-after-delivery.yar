rule Compile_After_Delivery {
 	meta:
		mitre = "T1027 Obfuscated File or Information: Compile After Delivery"
 	strings:
       		$a = "osacompile"
		$aA = "osacompile" base64
		$na = "NSAppleScript"
		$nb = "compileAndReturnError"
		$Na = "NSAppleScript" base64
		$Nb = "compileAndReturnError" base64


   	condition:
 		any of ($a*) or all of ($n*) or all of ($N*)
}