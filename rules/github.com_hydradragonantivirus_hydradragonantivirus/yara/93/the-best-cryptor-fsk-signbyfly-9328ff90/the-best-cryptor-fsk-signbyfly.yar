import "pe"
rule _The_Best_Cryptor__FsK____SignByfly_
{
	meta:
		description = "The Best Cryptor -> FsK   * Sign.By.fly"
	strings:
		$0 = {EB 06 56 52 55 4C 5A 00 90 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}