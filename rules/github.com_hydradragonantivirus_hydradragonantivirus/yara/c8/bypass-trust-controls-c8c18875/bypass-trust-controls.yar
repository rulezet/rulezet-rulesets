rule Bypass_Trust_Controls {
 	meta:
		mitre = "T1553 Bypass or Subvert Trust Controls" 		
 	strings:
       		$a = "xattr"  
		$b = "tccutil" 
		$c = "TCC.db"
		$d = "com.apple.quarantine"
       		$A = "xattr" base64 
		$B = "tccutil" base64
		$C = "TCC.db" base64
		$D = "com.apple.quarantine" base64
   	condition:
 		any of them
}