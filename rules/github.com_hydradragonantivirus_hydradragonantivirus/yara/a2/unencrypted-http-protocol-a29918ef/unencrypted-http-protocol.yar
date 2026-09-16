rule Unencrypted_HTTP_Protocol {
 	meta:
		mitre = "T1639.001 Exfiltration Over Unencrypted Non-C2 Protocol"
 	strings:
       		$h = "http://"
		$H = "http://" base64
		$apple = "http://www.apple.com/DTDs"
		$t = "tcp" fullword
		$t1 = "/dev/tcp"
		$T1 = "/dev/tcp" base64
   	condition:
 		any of them 
}