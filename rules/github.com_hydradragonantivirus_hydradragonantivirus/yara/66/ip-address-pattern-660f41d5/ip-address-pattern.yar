rule IP_Address_Pattern {
 	meta:
		mitre = "n/a"
 	strings:
       		$a = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
   	condition:
 		any of them
}