rule Win_Trojan_PS_21
{
strings:
	$a0 = { 2a2e636f6d00cd2000ba8000b41acd21c35dbf00015781ed06018db60c01a5a48d96d101e8e5ffb44e8d960601 }


condition:
	$a0
}