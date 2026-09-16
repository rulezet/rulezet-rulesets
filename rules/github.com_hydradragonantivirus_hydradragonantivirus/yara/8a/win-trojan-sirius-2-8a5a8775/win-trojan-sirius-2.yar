rule Win_Trojan_Sirius_2
{
strings:
	$a0 = { 3d66221542cebb96ccbe????0d4b18bfe2602ddec6ba32133ddf46bf36022d7f1bb9d10315de002d19e0bfbf378bfe31151d01f0bdbf07bf01e04248bb0d80bfff7ba93e00464647bff70115ff7dbf0dc0e2da }


condition:
	$a0
}