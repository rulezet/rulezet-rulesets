rule Win_Trojan_Vgen_109
{
strings:
	$a0 = { 6e64696e672073746f72792e2e2e0d0a24b80935cd21891e1b018c061d01ba0301b425cd21e890ffba8902cd27 }


condition:
	$a0
}