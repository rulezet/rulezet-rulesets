rule User_Discovery {
	meta:
	 	mitre = "T1033 System Owner/User Discovery"
 	strings:
       		$a = "whoami" 
		$b = "HOME"
		$c = "getenv"
       		$A = "whoami" base64 
		$B = "HOME" base64
		$C = "getenv" base64
   	condition:
 		any of them
}