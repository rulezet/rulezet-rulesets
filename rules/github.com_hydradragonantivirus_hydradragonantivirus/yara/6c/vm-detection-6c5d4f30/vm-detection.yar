rule VM_Detection {
        meta:
		mitre = "T1082 System Information Discovery"
 	strings:
       		$a = "ioreg-c"
		$a1 = "ioreg -c"
                $a2 = "ioreg -l"
		$a3 = "ioreg -rd"
		$a4 = "ioreg -ad2"
		$b = "IOPlatformExpertDevice"
		$c = "IOPlatformSerialNumber"
		$d = "vmware" nocase
		$e = "parallels" nocase
		$f = "SPHardwareDataType"
		$g = "SPNetworkDataType"
		$h = "SPUSBDataType"
		$i = "sysctl hw"
		$j = "hw.model"
		$k = "machdep.cpu.brand_string"
       		$A = "ioreg-c" base64
		$A1 = "ioreg -c" base64
                $A2 = "ioreg -l" base64
		$A3 = "ioreg -rd" base64
		$A4 = "ioreg -ad2" base64
		$B = "IOPlatformExpertDevice" base64
		$C = "IOPlatformSerialNumber" base64
		$D = "vmware" base64
		$D1 = "VMware" base64
		$E = "parallels" base64
		$E1 = "Parallels" base64
		$F = "SPHardwareDataType" base64
		$G = "SPNetworkDataType" base64
		$H = "SPUSBDataType" base64
		$I = "sysctl hw" base64
		$J = "hw.model" base64
		$K = "machdep.cpu.brand_string" base64
   	condition:
 		any of them 
}