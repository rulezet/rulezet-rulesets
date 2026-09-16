rule NET 
{
      meta:
		author="malware-lu"
	strings:
		
		$patternnet = ".NET" wide ascii
	condition:
		$patternnet
}