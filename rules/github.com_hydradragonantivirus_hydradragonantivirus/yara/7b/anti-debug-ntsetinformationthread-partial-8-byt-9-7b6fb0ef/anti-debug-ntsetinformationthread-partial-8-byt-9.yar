rule anti_debug__NtSetInformationThread__partial___8_byt_9_
{
strings:
	$a0 = { 6a006a006a116afee8 }

condition:
	$a0
}