rule Win_Trojan_Tu_2
{
strings:
	$a0 = { 81ebe20131c048cd21487403e81900fcbe860001debf000157a5a5bf0010a531c031db31ff31f6c3e890015331dbbf }


condition:
	$a0
}