import "pe"
rule _Phonebook_packed_datafile_
{
	meta:
		description = "Phonebook packed datafile"
	strings:
		$0 = {21 50 48 32 50 41 43 4B 24}
	condition:
		$0 at pe.entry_point
}