rule Win_Trojan_VGEN_549
{
strings:
	$a0 = { 2201e8a11571d0cdd2cac2d374fdcc420cc915cc4734417aa0d975e8cc3e68503656e6ced3ccea0009e041d90fcc87 }


condition:
	$a0
}