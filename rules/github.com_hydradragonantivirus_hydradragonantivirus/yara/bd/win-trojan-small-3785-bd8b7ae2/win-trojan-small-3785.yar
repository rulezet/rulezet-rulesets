rule Win_Trojan_Small_3785
{
strings:
	$a0 = { 855d82aadc62c2dc75b5e6ed3912979851f6ef0253f5f5f6aef859eddc89e8e9a4f3ed23cfa519fd599d21df8da05da708e69c1d1b27e494d0dc23485a9e9698dce3922360d0689b18d7eba4c5a0 }


condition:
	$a0
}