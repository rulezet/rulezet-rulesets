rule Win_Trojan_Brownie_1
{
strings:
	$a0 = { e8480283ee03b810efcd213cfd74448cd8488ed8bb8000291e0300291e1200ff361200b82135cd21061f8b }


condition:
	$a0
}