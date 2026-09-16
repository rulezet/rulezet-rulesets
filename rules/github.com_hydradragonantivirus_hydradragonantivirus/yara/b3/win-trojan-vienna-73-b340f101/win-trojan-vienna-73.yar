rule Win_Trojan_Vienna_73
{
strings:
	$a0 = { 03fc8bf281c6b900bf0001a5a58bf2ba1d0103d6b41acd1506b82435cd158cc08904895c02bafdff03d6b82425cd }


condition:
	$a0
}