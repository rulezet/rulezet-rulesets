rule BackOffPOS_1_55_DEC
{
meta:
	description = "BackoffPOS 1.56 LAST process injection code detection"
	in_the_wild = true

strings:
$a = "dec"
$b = "1.55"
$d = "Update"
$e = "Terminate"
$f = "Upload KeyLogs"
$g = "[Enter]"

condition:

all of them

}