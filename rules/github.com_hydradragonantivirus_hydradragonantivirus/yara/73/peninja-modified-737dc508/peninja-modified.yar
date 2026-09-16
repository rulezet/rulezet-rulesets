import "pe"
rule _PENinja_modified_
{
	meta:
		description = "PENinja modified"
	strings:
		$0 = {60 9C BE 8B FE B9 BB 44 52 4F 4C AD 33}
	condition:
		$0 at pe.entry_point
}