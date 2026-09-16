rule Win_Trojan_Loorp_1
{
strings:
	$a0 = { 558bec81ec84000000c745ec00????00c745cc433a5c??c745d0????????c745d4??????2ec745d865786500e8000000005ab93e02000083c20f8032f742e2fa9308c2c7f7f7f7af7eb22b7cb22b7cb7fb7cb7eb7cf77eb21f7cb21f7cb7ff7e }


condition:
	$a0
}