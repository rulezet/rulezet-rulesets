rule Win_Spyware_Banker_3309
{
strings:
	$a0 = { 6e041f07c423325befcbeef45d7aaa6621ad43fe1328b1f0200b5a0562dc83ea6108cc439b9644e2b227bbee3044464d6528a893ebb6399ea2e278577ec2b4a33ebc72a8d889d494fe4d7a191ffd42 }


condition:
	$a0
}