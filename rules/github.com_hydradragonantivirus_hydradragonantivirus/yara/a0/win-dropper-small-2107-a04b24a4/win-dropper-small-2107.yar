rule Win_Dropper_Small_2107
{
strings:
	$a0 = { bf0510400083ec308bece8c8ffffffe8c3ffffff33edbb00144000bef00141009090680020010055ff542428a3001e400083ee048b0ee30f }


condition:
	$a0
}