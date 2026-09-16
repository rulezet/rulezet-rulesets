rule Win_Trojan_Subsys_24
{
strings:
	$a0 = { a1cd1d5002d78ea5da3e845fd6c55c06ff0818737c06d75ecd10deb2e361fa31c39186a5175bc4e7dd8473f5fd059336 }


condition:
	$a0
}