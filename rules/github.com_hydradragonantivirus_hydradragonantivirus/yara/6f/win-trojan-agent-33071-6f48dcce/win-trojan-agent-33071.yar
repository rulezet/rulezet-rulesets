rule Win_Trojan_Agent_33071
{
strings:
	$a0 = { 1b0af27217ad5715796344d84558eb80d58ffb665f30cf38ecf29bbde67bebf1c1e965d132a12657dc8513ba7e4be2206ce5aac29d5a53ae6e96961c9c09ff9790bca921fbeed11ec636bfb65eeb }


condition:
	$a0
}