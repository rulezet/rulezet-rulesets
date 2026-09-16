rule java
{
      meta:
		author="malware-lu"
	strings:
		$patternjava = "java" wide ascii
	condition:
		$patternjava
}