rule Win_Downloader_Agent_31844
{
strings:
	$a0 = { 5da38688f6c65932dd5cbc8607849804625c07ed578c6e9702fda7631e7e7073678e438a617df3bac80a11218764e47f7efbcfd61fa127ed2fcf82c670dddeceb0d161c8df19ffb0b70786 }


condition:
	$a0
}