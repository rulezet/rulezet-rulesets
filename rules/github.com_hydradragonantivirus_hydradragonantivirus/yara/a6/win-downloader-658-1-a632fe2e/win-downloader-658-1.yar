rule Win_Downloader_658_1
{
strings:
	$a0 = { 31d25252bab817????ff1209c0752a89c281c2cbaceaf3??c23565560c8d8a3c050000520577d7afb12902ff0a31c083c20283c20239ca7eebbad6174100ff12 }


condition:
	$a0
}