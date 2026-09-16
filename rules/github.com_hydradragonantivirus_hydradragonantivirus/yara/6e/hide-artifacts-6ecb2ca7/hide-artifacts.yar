rule Hide_Artifacts {
 	meta:
		mitre = "T1564 Hide Artifacts"
 	strings:
       		$a = "mktemp -d"
		$b = "mktemp -t"
		$c = "mkdir -p /tmp"
       		$A = "mktemp -d" base64
		$B = "mktemp -t" base64
		$C = "mkdir -p /tmp" base64
   	condition:
 		any of them
}