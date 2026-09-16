rule Win_Spyware_Lineage_9
{
strings:
	$a0 = { 5688d80e8a0b3fc7f880bf0988390213b34c696e65616737a9ffbf6594646f777320436c69656e74d39b0d8158b01f2f27 }


condition:
	$a0
}