rule Win_Dropper_Agent_33660
{
strings:
	$a0 = { cde7469097acb152ba362686fc8cc5c6cbca5fd86a8d44e12201ccbf8714d63cdaf6f8db10eac4270da79590cf86d2e8fea0f672088e843a1256089e13185a057696b98b8d27ff4efdc2b161c0c48881 }


condition:
	$a0
}